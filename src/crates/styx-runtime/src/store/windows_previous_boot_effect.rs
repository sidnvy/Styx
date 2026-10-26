//! Actual fixed previous-boot file effects. Only the parent opaque same-journal
//! recovery coordinator calls `execute` after its durable Prepared phase.
//! No Drop unlinks files. Errors retain every opened original/created HANDLE.
use super::*;
use crate::store::platform::restart::StartupLinkCustody;
use crate::store::{ConfigurationMaintenance, OwnedConfigurationRoot};
use std::os::windows::fs::FileExt;
use styx_contracts::identity::TransactionId;

const GUARDS: &[&str] = &[
    "advance.lock",
    "background.lock",
    "capabilities.lock",
    "foreground.lock",
];
struct OriginalPin {
    index: usize,
    handle: Option<File>,
    renamed: bool,
    post: Option<FileObservation>,
}
struct CreatedPin {
    name: &'static str,
    handle: Option<File>,
    original: Option<FileObservation>,
    written: Option<FileObservation>,
}
/// Original recovery owner; the shared journal and actual OS observation remain
/// held by the coordinator on the same blocking worker. Never Deserialize/Clone.
pub(in crate::store) struct WindowsBootRecoveryEffects {
    evidence: WindowsPreviousBootEvidence,
    owner: OwnedConfigurationRoot,
    maintenance: ConfigurationMaintenance,
    transaction: TransactionId,
    guard_bytes: Vec<u8>,
    archive: Option<Root>,
    service: Option<(Root, RawFile)>,
    legacy_identity: Option<(Root, RawFile, u32)>,
    startup: Option<StartupLinkCustody>,
    original_pins: Vec<OriginalPin>,
    created: Vec<CreatedPin>,
    attempted: bool,
    archived: bool,
    guards_attempted: bool,
    marker_retired: bool,
    completed: bool,
}
fn read_pin(file: &File, expected: &[u8]) -> JournalResult<FileObservation> {
    let before = private_facts(file, false).map_err(failed)?.observation;
    if before.byte_len != expected.len() as u64 {
        return Err(JournalError::Conflict);
    }
    let mut data = vec![0u8; expected.len() + 1];
    let mut n = 0;
    while n < data.len() {
        let k = file.seek_read(&mut data[n..], n as u64).map_err(failed)?;
        if k == 0 {
            break;
        }
        n += k;
    }
    if n != expected.len()
        || &data[..n] != expected
        || private_facts(file, false).map_err(failed)?.observation != before
    {
        return Err(JournalError::Conflict);
    }
    Ok(before)
}
fn cutover_stamp(
    file: &File,
    expected: &[u8],
) -> JournalResult<crate::store::management::handoff::NativeRetirementFileStamp> {
    let observation = read_pin(file, expected)?;
    let facts = private_facts(file, false).map_err(failed)?;
    let owner_sid = ffi::private(file).map_err(failed)?;
    if facts.observation != observation {
        return Err(JournalError::Unknown);
    }
    Ok(
        crate::store::management::handoff::NativeRetirementFileStamp::Windows {
            volume_serial: observation.device,
            file_id: observation.inode,
            owner_sid,
            nlink: u64::from(facts.links),
            byte_len: observation.byte_len,
            modified_seconds: observation.modified_seconds,
            modified_nanoseconds: observation.modified_nanoseconds,
            changed_seconds: observation.changed_seconds,
            changed_nanoseconds: observation.changed_nanoseconds,
            sha256: styx_contracts::identity::Sha256Digest::of_bytes(expected),
        },
    )
}
fn same_moved(a: &FileObservation, b: &FileObservation) -> bool {
    a.device == b.device
        && a.inode == b.inode
        && a.byte_len == b.byte_len
        && a.modified_seconds == b.modified_seconds
        && a.modified_nanoseconds == b.modified_nanoseconds
}
fn maybe_raw(root: &Root, name: &str) -> JournalResult<Option<RawFile>> {
    match root.read_raw(Path::new(name), 32768) {
        Ok(raw) => Ok(Some(raw)),
        Err(StoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            root.ensure_absent(Path::new(name)).map_err(failed)?;
            Ok(None)
        }
        Err(_) => Err(JournalError::Unknown),
    }
}
impl WindowsBootRecoveryEffects {
    /// This construction is read-only. Original raw guard bytes are serialized
    /// by the shared journal Prepared builder and its hash is retained there.
    /// Schema/transaction/root/process/generation validation belongs to that
    /// single builder, not a caller-controlled arbitrary lock text.
    pub(super) fn new(
        evidence: WindowsPreviousBootEvidence,
        owner: OwnedConfigurationRoot,
        maintenance: ConfigurationMaintenance,
        transaction: TransactionId,
        guard_bytes: Vec<u8>,
    ) -> JournalResult<Self> {
        if guard_bytes.is_empty()
            || guard_bytes.len() > 4096
            || maintenance.transaction_id() != &transaction
        {
            return Err(JournalError::InvalidInput);
        }
        owner.with_maintenance(&maintenance, |state| {
            if state.root.identity() != evidence.root.identity() {
                return Err(JournalError::Conflict);
            }
            Ok(())
        })?;
        Ok(Self {
            evidence,
            owner,
            maintenance,
            transaction,
            guard_bytes,
            archive: None,
            service: None,
            legacy_identity: None,
            startup: None,
            original_pins: vec![],
            created: vec![],
            attempted: false,
            archived: false,
            guards_attempted: false,
            marker_retired: false,
            completed: false,
        })
    }
    /// Revalidate original C custody for canonical publication. This accepts
    /// only the opaque same-owner GuardsHeld, never serialized cleanup claims.
    /// All original later-boot/startup checks remain in validate_guards().
    pub(in crate::store) fn validate_cutover_custody(
        &self,
        owner: &OwnedConfigurationRoot,
        held: &crate::store::management::handoff::LegacyGuardsHeld,
        observation: &WindowsLegacyObservation,
    ) -> JournalResult<()> {
        use crate::store::management::handoff::{OwnerRecoveryStage, ProofStamp};
        let prepared = held.prepared();
        let intent = prepared.intent();
        let actual_root = match self.evidence.root.identity() {
            RootIdentity::Windows {
                volume_serial,
                file_id,
                owner_sid,
            } => styx_contracts::native_management::NativeRootIdentity::Windows {
                volume_serial,
                file_id,
                owner_sid,
            },
            _ => return Err(JournalError::Conflict),
        };
        if !self.owner.same_authority(owner)
            || !self.maintenance.matches(owner)
            || !prepared.matches_owner(owner)
            || intent.transaction_id != self.transaction
            || self.maintenance.transaction_id() != &self.transaction
            || intent.config_root != actual_root
            || prepared.stage() != Some(OwnerRecoveryStage::GuardsHeld)
            || (intent.schema == 3 && self.startup.is_none())
        {
            return Err(JournalError::Conflict);
        }
        self.validate_guards(observation)?;
        let originals = prepared
            .archived_original_posts()
            .ok_or(JournalError::Conflict)?;
        let guards = prepared.guards_held_posts().ok_or(JournalError::Conflict)?;
        if originals.len() != prepared.originals().len()
            || originals.len() != self.original_pins.len()
            || guards.len() != prepared.guard_bytes().len()
            || guards.len() != GUARDS.len()
        {
            return Err(JournalError::Conflict);
        }
        self.owner.with_maintenance(&self.maintenance, |_| {
            for (original, post) in prepared.originals().iter().zip(originals) {
                if original.name != post.name || !original.stamp.same_file_after_rename(&post.stamp)
                {
                    return Err(JournalError::Conflict);
                }
                let pin = self
                    .original_pins
                    .iter()
                    .find(|pin| {
                        self.evidence.originals[pin.index].relative_path()
                            == Path::new(original.name.source_name())
                    })
                    .ok_or(JournalError::Unknown)?;
                let saved = &self.evidence.originals[pin.index];
                if saved.bytes() != original.raw
                    || cutover_stamp(
                        pin.handle.as_ref().ok_or(JournalError::Unknown)?,
                        &original.raw,
                    )? != post.stamp
                {
                    return Err(JournalError::Unknown);
                }
            }
            for (binding, post) in prepared.guard_bytes().iter().zip(guards) {
                if binding.name != post.name || binding.raw != self.guard_bytes {
                    return Err(JournalError::Conflict);
                }
                let pin = self
                    .created
                    .iter()
                    .find(|pin| pin.name == binding.name.source_name())
                    .ok_or(JournalError::Unknown)?;
                if cutover_stamp(
                    pin.handle.as_ref().ok_or(JournalError::Unknown)?,
                    &binding.raw,
                )? != post.stamp
                {
                    return Err(JournalError::Unknown);
                }
            }
            Ok(())
        })?;
        self.validate_guards(observation)
    }
    /// Private OS engine. Parent verifies the opaque Prepared's exact owner,
    /// original receipts, boot epoch, tx, archive path and guard digest before
    /// entering here. It appends observed stages only after actual rereads.
    pub(super) fn execute_archive(
        &mut self,
        observation: &WindowsLegacyObservation,
    ) -> JournalResult<()> {
        if self.attempted {
            return Err(JournalError::Conflict);
        }
        self.evidence.revalidate(observation)?;
        self.attempted = true;
        self.archive_pending(observation, false)
    }
    /// Explicit original-ID recovery, only after the parent validates the SAME
    /// durable Prepared and its immutable original attachments. This classifies
    /// every effect from protected OS facts; it never replays a Done or Unknown.
    pub(super) fn resume_archive(
        &mut self,
        observation: &WindowsLegacyObservation,
    ) -> JournalResult<()> {
        self.validate_context(observation)?;
        // Release only pins whose actual object is still the expected source or
        // fixed destination. Unknown objects retain custody and stop recovery.
        for pin in &self.original_pins {
            if let Some(file) = &pin.handle {
                let raw = &self.evidence.originals[pin.index];
                if !same_moved(raw.observation(), &read_pin(file, raw.bytes())?) {
                    return Err(JournalError::Unknown);
                }
                let path = ffi::final_path(file).map_err(failed)?;
                let source = self.evidence.root.path.join(raw.relative_path());
                let destination = self
                    .evidence
                    .root
                    .path
                    .join("foreground-recovery")
                    .join(self.transaction.as_str())
                    .join(format!(
                        "{}.retired",
                        raw.relative_path()
                            .to_str()
                            .ok_or(JournalError::InvalidInput)?
                    ));
                if path != source && path != destination {
                    return Err(JournalError::Unknown);
                }
            }
        }
        self.original_pins.clear();
        self.attempted = true;
        self.archive_pending(observation, true)
    }
    fn validate_context(&self, observation: &WindowsLegacyObservation) -> JournalResult<()> {
        self.evidence.root.validate_root().map_err(failed)?;
        if let Some(startup) = &self.startup {
            startup.validate_excluded(&self.maintenance, observation)?;
            startup.observe_later_boot_while_excluded(&self.maintenance, observation)?;
        }
        if let Some((host, original)) = &self.service {
            let actual = host
                .read_raw(Path::new("service.json"), 32768)
                .map_err(failed)?;
            if actual.observation() != original.observation() || actual.bytes() != original.bytes()
            {
                return Err(JournalError::Conflict);
            }
        }
        if let Some((host, identity, pid)) = &self.legacy_identity {
            let actual = host
                .read_raw(identity.relative_path(), identity.bytes().len())
                .map_err(failed)?;
            if actual.observation() != identity.observation()
                || actual.bytes() != identity.bytes()
                || ffi::process_optional(*pid).map_err(failed)?.is_some()
            {
                return Err(JournalError::Conflict);
            }
            self.evidence
                .root
                .ensure_absent(Path::new("foreground-owner.json"))
                .map_err(failed)?;
        }
        self.owner.with_maintenance(&self.maintenance, |state| {
            if state.root.identity() != self.evidence.root.identity() {
                return Err(JournalError::Conflict);
            }
            Ok(())
        })?;
        let original = &self.evidence.originals[0];
        let actual = self
            .evidence
            .root
            .read_raw(original.relative_path(), original.bytes().len())
            .map_err(failed)?;
        if actual.bytes() != original.bytes()
            || actual.observation() != original.observation()
            || observation.checkpoint().map_err(failed)? != self.evidence.current_boot
        {
            return Err(JournalError::Conflict);
        }
        Ok(())
    }
    fn ensure_archive(&mut self, resume: bool) -> JournalResult<()> {
        if self.archive.is_none() {
            let parent = self
                .evidence
                .root
                .create_journal_directory("foreground-recovery", false)
                .map_err(failed)?;
            let parent = Root::from_directory_handle(&parent).map_err(failed)?;
            let dir = parent
                .create_journal_directory(self.transaction.as_str(), !resume)
                .map_err(failed)?;
            self.archive = Some(Root::from_directory_handle(&dir).map_err(failed)?);
            parent.sync_directory().map_err(failed)?;
            self.evidence.root.sync_directory().map_err(failed)?;
        }
        let archive = self.archive.as_ref().ok_or(JournalError::Unknown)?;
        // No adoption of arbitrary existing archive content.
        for item in std::fs::read_dir(&archive.path).map_err(failed)? {
            let item = item.map_err(failed)?;
            let name = item.file_name();
            let name = name.to_str().ok_or(JournalError::Conflict)?;
            // Startup retains and validates this original non-private-ACL link.
            // Never route it through private read_raw or accept it without custody.
            if name == "windows-startup-original.lnk" && self.startup.is_some() {
                continue;
            }
            let known = name == "foreground-recovery.lock.retired"
                || self.evidence.originals.iter().skip(1).any(|r| {
                    r.relative_path().to_str().is_some_and(|n| {
                        name == format!("{n}.before") || name == format!("{n}.retired")
                    })
                });
            if !known {
                return Err(JournalError::Conflict);
            }
            archive.read_raw(Path::new(name), 32768).map_err(failed)?;
        }
        archive.validate_root().map_err(failed)
    }
    fn archive_pending(
        &mut self,
        observation: &WindowsLegacyObservation,
        resume: bool,
    ) -> JournalResult<()> {
        self.validate_context(observation)?;
        if resume {
            self.ensure_archive(true)?;
        }
        if resume && self.restore_retired_marker()? {
            for name in GUARDS {
                self.reopen_guard(name)?;
            }
        } else {
            self.ensure_guard("foreground-recovery.lock", resume)?;
            for name in &GUARDS[..3] {
                self.ensure_guard(name, resume)?;
            }
        }
        self.ensure_archive(resume)?;
        for index in 1..self.evidence.originals.len() {
            self.archive_one(index, resume)?;
            self.validate_context(observation)?;
        }
        if resume && !self.marker_retired {
            if maybe_raw(&self.evidence.root, "foreground.lock")?.is_some() {
                self.reopen_guard("foreground.lock")?;
            }
        }
        if self.marker_retired {
            self.observe_complete(observation)?;
            self.archived = true;
            self.completed = true;
        } else {
            self.observe_archived(observation)?;
            self.archived = true;
        }
        Ok(())
    }
    fn archive_one(&mut self, index: usize, resume: bool) -> JournalResult<()> {
        let raw = &self.evidence.originals[index];
        let name = raw
            .relative_path()
            .to_str()
            .ok_or(JournalError::InvalidInput)?;
        let destination = format!("{name}.retired");
        let backup_name = format!("{name}.before");
        let archive = self.archive.as_ref().ok_or(JournalError::Unknown)?;
        let source = maybe_raw(&self.evidence.root, name)?;
        let destination_raw = maybe_raw(archive, &destination)?;
        let (file, already_done) = match (source.as_ref(), destination_raw.as_ref()) {
            (Some(source), None)
                if source.bytes() == raw.bytes()
                    && source.observation() == raw.observation()
                    && !self.marker_retired =>
            {
                let file = ffi::open_retirement_token(&self.evidence.root.path.join(name))
                    .map_err(failed)?;
                if read_pin(&file, raw.bytes())? != *raw.observation() {
                    return Err(JournalError::Conflict);
                }
                (file, false)
            }
            (source, Some(done))
                if resume
                    && done.bytes() == raw.bytes()
                    && same_moved(raw.observation(), done.observation())
                    && (source.is_none()
                        || (name == "foreground.lock"
                            && source.is_some_and(|s| s.bytes() == self.guard_bytes))) =>
            {
                let file =
                    ffi::open_retirement_token(&archive.path.join(&destination)).map_err(failed)?;
                if read_pin(&file, raw.bytes())? != *done.observation() {
                    return Err(JournalError::Unknown);
                }
                (file, true)
            }
            _ => return Err(JournalError::Unknown),
        };
        self.original_pins.push(OriginalPin {
            index,
            handle: Some(file),
            renamed: already_done,
            post: None,
        });
        let pin = self.original_pins.last_mut().ok_or(JournalError::Unknown)?;
        match maybe_raw(archive, &backup_name)? {
            Some(backup) if resume && backup.bytes() == raw.bytes() => {}
            None if !already_done => {
                let mut backup = archive.new_journal_file(&backup_name).map_err(failed)?;
                backup.write_all(raw.bytes()).map_err(failed)?;
                ffi::flush_file(&backup).map_err(failed)?;
                drop(backup);
                if archive
                    .read_raw(Path::new(&backup_name), raw.bytes().len())
                    .map_err(failed)?
                    .bytes()
                    != raw.bytes()
                {
                    return Err(JournalError::Unknown);
                }
            }
            _ => return Err(JournalError::Unknown),
        }
        if !already_done {
            let file = pin.handle.as_ref().ok_or(JournalError::Unknown)?;
            ffi::require_no_streams(&self.evidence.root.path.join(name)).map_err(failed)?;
            ffi::rename_journal_file(file, &archive.directory, &destination, false)
                .map_err(failed)?;
            pin.renamed = true;
            ffi::flush_file(file).map_err(failed)?;
            if !same_moved(raw.observation(), &read_pin(file, raw.bytes())?) {
                return Err(JournalError::Unknown);
            }
        }
        // Recovery re-flushes the exact already-renamed original; this is not
        // another rename or credential/business action.
        ffi::flush_file(pin.handle.as_ref().ok_or(JournalError::Unknown)?).map_err(failed)?;
        drop(pin.handle.take());
        pin.handle =
            Some(ffi::open(&archive.path.join(&destination), false, false, false).map_err(failed)?);
        let post = read_pin(
            pin.handle.as_ref().ok_or(JournalError::Unknown)?,
            raw.bytes(),
        )?;
        if !same_moved(raw.observation(), &post) {
            return Err(JournalError::Unknown);
        }
        pin.post = Some(post);
        archive.sync_directory().map_err(failed)?;
        self.evidence.root.sync_directory().map_err(failed)?;
        Ok(())
    }
    /// Called only after the shared journal recorded Archived for this exact
    /// original effect object. No retry if CREATE_NEW or a later observation
    /// fails: the preserved object exposes read-only observe_complete instead.
    pub(super) fn finish_guards(
        &mut self,
        observation: &WindowsLegacyObservation,
    ) -> JournalResult<()> {
        if !self.archived
            || self.guards_attempted
            || self.completed
            || self.created.iter().any(|g| g.name == "foreground.lock")
        {
            return Err(JournalError::Conflict);
        }
        self.observe_archived(observation)?;
        self.guards_attempted = true;
        self.ensure_guard("foreground.lock", false)?;
        self.retire_recovery_marker()?;
        self.observe_complete(observation)?;
        self.completed = true;
        Ok(())
    }
    /// Explicit original-transaction continuation after a partial final guard
    /// phase. Existing matching guards are revalidated/flushed, never rewritten.
    pub(super) fn resume_guards(
        &mut self,
        observation: &WindowsLegacyObservation,
    ) -> JournalResult<()> {
        self.validate_context(observation)?;
        if self.restore_retired_marker()? {
            self.observe_complete(observation)?;
            self.completed = true;
            return Ok(());
        }
        self.observe_archived(observation)?;
        self.guards_attempted = true;
        self.ensure_guard("foreground.lock", true)?;
        self.retire_recovery_marker()?;
        self.observe_complete(observation)?;
        self.completed = true;
        Ok(())
    }
    /// Replace temporary recovery exclusion with the four durable legacy
    /// writer guards. Preserve the temporary marker in the same fixed archive;
    /// never unlink old/new unknown locks or leave a successful C phase blocked
    /// solely by its temporary foreground-recovery marker.
    fn retire_recovery_marker(&mut self) -> JournalResult<()> {
        if self.marker_retired || self.created.len() != 5 {
            return Err(JournalError::Conflict);
        }
        let archive = self.archive.as_ref().ok_or(JournalError::Unknown)?;
        let pin = self
            .created
            .iter_mut()
            .find(|p| p.name == "foreground-recovery.lock")
            .ok_or(JournalError::Unknown)?;
        let expected = pin.written.clone().ok_or(JournalError::Unknown)?;
        if read_pin(
            pin.handle.as_ref().ok_or(JournalError::Unknown)?,
            &self.guard_bytes,
        )? != expected
        {
            return Err(JournalError::Unknown);
        }
        drop(pin.handle.take());
        let path = self.evidence.root.path.join(pin.name);
        let original = ffi::open_retirement_token(&path).map_err(failed)?;
        pin.handle = Some(original);
        let original = pin.handle.as_ref().ok_or(JournalError::Unknown)?;
        if read_pin(original, &self.guard_bytes)? != expected {
            return Err(JournalError::Unknown);
        }
        let destination = "foreground-recovery.lock.retired";
        archive
            .ensure_absent(Path::new(destination))
            .map_err(failed)?;
        ffi::rename_journal_file(original, &archive.directory, destination, false)
            .map_err(failed)?;
        ffi::flush_file(original).map_err(failed)?;
        drop(pin.handle.take());
        let read =
            ffi::open(&archive.path.join(destination), false, false, false).map_err(failed)?;
        pin.handle = Some(read);
        let after = read_pin(
            pin.handle.as_ref().ok_or(JournalError::Unknown)?,
            &self.guard_bytes,
        )?;
        if !same_moved(&expected, &after) {
            return Err(JournalError::Unknown);
        }
        pin.written = Some(after);
        archive.sync_directory().map_err(failed)?;
        self.evidence.root.sync_directory().map_err(failed)?;
        self.evidence
            .root
            .ensure_absent(Path::new(pin.name))
            .map_err(failed)?;
        self.marker_retired = true;
        Ok(())
    }
    fn reopen_guard(&mut self, name: &'static str) -> JournalResult<()> {
        let expected = if let Some(pin) = self.created.iter_mut().find(|p| p.name == name) {
            let file = pin.handle.as_ref().ok_or(JournalError::Unknown)?;
            let actual = read_pin(file, &self.guard_bytes)?;
            let original = pin.original.as_ref().ok_or(JournalError::Unknown)?;
            if actual.device != original.device || actual.inode != original.inode {
                return Err(JournalError::Unknown);
            }
            if pin
                .written
                .as_ref()
                .is_some_and(|w| !same_moved(w, &actual))
            {
                return Err(JournalError::Unknown);
            }
            if ffi::final_path(file).map_err(failed)? != self.evidence.root.path.join(name) {
                return Err(JournalError::Unknown);
            }
            drop(pin.handle.take());
            actual
        } else {
            let raw = maybe_raw(&self.evidence.root, name)?.ok_or(JournalError::Unknown)?;
            if raw.bytes() != self.guard_bytes {
                return Err(JournalError::Conflict);
            }
            raw.observation().clone()
        };
        let file =
            ffi::open_retirement_token(&self.evidence.root.path.join(name)).map_err(failed)?;
        let index = if let Some(i) = self.created.iter().position(|p| p.name == name) {
            self.created[i].handle = Some(file);
            i
        } else {
            self.created.push(CreatedPin {
                name,
                handle: Some(file),
                original: Some(expected.clone()),
                written: None,
            });
            self.created.len() - 1
        };
        let pin = &mut self.created[index];
        let file = pin.handle.as_ref().ok_or(JournalError::Unknown)?;
        let actual = read_pin(file, &self.guard_bytes)?;
        if !same_moved(&actual, &expected) {
            return Err(JournalError::Unknown);
        }
        ffi::flush_file(file).map_err(failed)?;
        drop(pin.handle.take());
        let file =
            ffi::open(&self.evidence.root.path.join(name), false, false, false).map_err(failed)?;
        pin.handle = Some(file);
        let after = read_pin(
            pin.handle.as_ref().ok_or(JournalError::Unknown)?,
            &self.guard_bytes,
        )?;
        if !same_moved(&after, &expected) {
            return Err(JournalError::Unknown);
        }
        pin.written = Some(after);
        self.evidence.root.sync_directory().map_err(failed)
    }
    fn ensure_guard(&mut self, name: &'static str, resume: bool) -> JournalResult<()> {
        if self.created.iter().any(|p| p.name == name) {
            return self.reopen_guard(name);
        }
        if resume && maybe_raw(&self.evidence.root, name)?.is_some() {
            return self.reopen_guard(name);
        }
        self.create_guard(name)
    }
    fn restore_retired_marker(&mut self) -> JournalResult<bool> {
        let archive = self.archive.as_ref().ok_or(JournalError::Unknown)?;
        if let Some(pin) = self
            .created
            .iter_mut()
            .find(|p| p.name == "foreground-recovery.lock")
        {
            if let Some(file) = &pin.handle {
                let actual = read_pin(file, &self.guard_bytes)?;
                if pin
                    .written
                    .as_ref()
                    .is_some_and(|w| !same_moved(w, &actual))
                {
                    return Err(JournalError::Unknown);
                }
                let path = ffi::final_path(file).map_err(failed)?;
                if path == archive.path.join("foreground-recovery.lock.retired") {
                    drop(pin.handle.take());
                } else if path != self.evidence.root.path.join(pin.name) {
                    return Err(JournalError::Unknown);
                }
            }
        }
        let Some(raw) = maybe_raw(archive, "foreground-recovery.lock.retired")? else {
            return Ok(false);
        };
        if raw.bytes() != self.guard_bytes {
            return Err(JournalError::Conflict);
        }
        self.evidence
            .root
            .ensure_absent(Path::new("foreground-recovery.lock"))
            .map_err(failed)?;
        if let Some(pin) = self
            .created
            .iter_mut()
            .find(|p| p.name == "foreground-recovery.lock")
        {
            if let Some(file) = &pin.handle {
                if !same_moved(
                    &raw.observation().clone(),
                    &read_pin(file, &self.guard_bytes)?,
                ) {
                    return Err(JournalError::Unknown);
                }
            }
            drop(pin.handle.take());
        }
        let file = ffi::open(
            &archive.path.join("foreground-recovery.lock.retired"),
            false,
            false,
            false,
        )
        .map_err(failed)?;
        let actual = read_pin(&file, &self.guard_bytes)?;
        if &actual != raw.observation() {
            return Err(JournalError::Unknown);
        }
        self.created
            .retain(|p| p.name != "foreground-recovery.lock");
        self.created.push(CreatedPin {
            name: "foreground-recovery.lock",
            handle: Some(file),
            original: Some(actual.clone()),
            written: Some(actual),
        });
        self.marker_retired = true;
        Ok(true)
    }
    fn create_guard(&mut self, name: &'static str) -> JournalResult<()> {
        self.evidence.root.validate_root().map_err(failed)?;
        if let Some((host, original)) = &self.service {
            let actual = host
                .read_raw(Path::new("service.json"), 32768)
                .map_err(failed)?;
            if actual.observation() != original.observation() || actual.bytes() != original.bytes()
            {
                return Err(JournalError::Conflict);
            }
        }
        let path = self.evidence.root.path.join(name);
        let file = ffi::create_new_private_file(&path).map_err(failed)?;
        self.created.push(CreatedPin {
            name,
            handle: Some(file),
            original: None,
            written: None,
        });
        let pin = self.created.last_mut().ok_or(JournalError::Unknown)?;
        let file = pin.handle.as_mut().ok_or(JournalError::Unknown)?;
        let original = private_facts(file, false).map_err(failed)?.observation;
        pin.original = Some(original.clone());
        file.write_all(&self.guard_bytes).map_err(failed)?;
        ffi::flush_file(file).map_err(failed)?;
        let written = read_pin(file, &self.guard_bytes)?;
        drop(pin.handle.take());
        let read = ffi::open(&path, false, false, false).map_err(failed)?;
        let after = read_pin(&read, &self.guard_bytes)?;
        if !same_moved(&written, &after)
            || after.device != original.device
            || after.inode != original.inode
        {
            return Err(JournalError::Unknown);
        }
        pin.written = Some(after);
        pin.handle = Some(read);
        self.evidence.root.sync_directory().map_err(failed)
    }
    /// Read-only resync of the exact original attempted effects. Never retries
    /// a rename/create and never treats a partial state as complete. The shared
    /// journal may append a missing observed receipt only if this succeeds.
    pub(super) fn observe_complete(
        &self,
        observation: &WindowsLegacyObservation,
    ) -> JournalResult<()> {
        self.observe_effects(observation, true)
    }
    pub(super) fn observe_archived(
        &self,
        observation: &WindowsLegacyObservation,
    ) -> JournalResult<()> {
        self.observe_effects(observation, false)
    }
    fn observe_effects(
        &self,
        observation: &WindowsLegacyObservation,
        complete: bool,
    ) -> JournalResult<()> {
        self.evidence.root.validate_root().map_err(failed)?;
        if let Some((host, original)) = &self.service {
            let actual = host
                .read_raw(Path::new("service.json"), 32768)
                .map_err(failed)?;
            if actual.observation() != original.observation() || actual.bytes() != original.bytes()
            {
                return Err(JournalError::Conflict);
            }
        }
        let archive = self.archive.as_ref().ok_or(JournalError::Unknown)?;
        archive.validate_root().map_err(failed)?;
        if observation.checkpoint().map_err(failed)? != self.evidence.current_boot
            || (complete && self.created.len() != 5)
            || (!complete && !matches!(self.created.len(), 4 | 5))
        {
            return Err(JournalError::Conflict);
        }
        for pin in &self.created {
            let after = read_pin(
                pin.handle.as_ref().ok_or(JournalError::Unknown)?,
                &self.guard_bytes,
            )?;
            if Some(&after) != pin.written.as_ref() {
                return Err(JournalError::Unknown);
            }
            let original = pin.original.as_ref().ok_or(JournalError::Unknown)?;
            if after.device != original.device || after.inode != original.inode {
                return Err(JournalError::Unknown);
            }
            let named = if pin.name == "foreground-recovery.lock" && complete {
                if !self.marker_retired {
                    return Err(JournalError::Unknown);
                }
                self.evidence
                    .root
                    .ensure_absent(Path::new(pin.name))
                    .map_err(failed)?;
                archive
                    .read_raw(
                        Path::new("foreground-recovery.lock.retired"),
                        self.guard_bytes.len(),
                    )
                    .map_err(failed)?
            } else {
                self.evidence
                    .root
                    .read_raw(Path::new(pin.name), self.guard_bytes.len())
                    .map_err(failed)?
            };
            if named.observation() != &after || named.bytes() != self.guard_bytes {
                return Err(JournalError::Unknown);
            }
        }
        for pin in &self.original_pins {
            let raw = &self.evidence.originals[pin.index];
            let name = raw
                .relative_path()
                .to_str()
                .ok_or(JournalError::InvalidInput)?;
            if !pin.renamed {
                return Err(JournalError::Unknown);
            }
            let after = read_pin(
                pin.handle.as_ref().ok_or(JournalError::Unknown)?,
                raw.bytes(),
            )?;
            if Some(&after) != pin.post.as_ref() {
                return Err(JournalError::Unknown);
            }
            let named = archive
                .read_raw(Path::new(&format!("{name}.retired")), raw.bytes().len())
                .map_err(failed)?;
            if named.observation() != &after || named.bytes() != raw.bytes() {
                return Err(JournalError::Unknown);
            }
            let backup = archive
                .read_raw(Path::new(&format!("{name}.before")), raw.bytes().len())
                .map_err(failed)?;
            if backup.bytes() != raw.bytes() {
                return Err(JournalError::Unknown);
            }
            if name != "foreground.lock"
                || !self.created.iter().any(|p| p.name == "foreground.lock")
            {
                self.evidence
                    .root
                    .ensure_absent(raw.relative_path())
                    .map_err(failed)?;
            }
        }
        // Full original configuration remains byte/file-identical.
        let deployment = &self.evidence.originals[0];
        let current = self
            .evidence
            .root
            .read_raw(deployment.relative_path(), deployment.bytes().len())
            .map_err(failed)?;
        if current.observation() != deployment.observation()
            || current.bytes() != deployment.bytes()
        {
            return Err(JournalError::Conflict);
        }
        if observation.checkpoint().map_err(failed)? != self.evidence.current_boot {
            return Err(JournalError::Conflict);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Cleanup(Option<PathBuf>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Some(path) = self.0.take() {
                let _ = std::fs::remove_dir_all(path);
            }
        }
    }
    /// Actual owned NTFS file-effect fixture, not a fabricated prior-reboot or
    /// original legacy execution settlement acceptance. WMI/TaskFolder are real;
    /// only the old receipt bytes are synthetic, constructed directly below.
    #[test]
    #[ignore = "requires STYX_TEST_WINDOWS_STORE_ROOT; owned NTFS + native WMI/TaskScheduler"]
    fn original_owner_archive_guard_acquisition_and_collision() {
        let base = PathBuf::from(std::env::var("STYX_TEST_WINDOWS_STORE_ROOT").unwrap());
        let parent = Root::open(&base).unwrap();
        for conflict in [false, true] {
            let name = format!("r60-{}", uuid::Uuid::new_v4().simple());
            let mut cleanup = Cleanup(None);
            let root = match parent.create_fresh_child(OsStr::new(&name)) {
                Ok(root) => root,
                Err(_) => panic!("fresh private fixture"),
            };
            cleanup.0 = Some(base.join(&name));
            let private = PrivateRoot {
                inner: root.clone(),
            };
            let writer = private.try_configuration_writer().unwrap();
            for (name, bytes) in [
                ("deployment.json", b"{}".as_slice()),
                ("state.json", b"{}".as_slice()),
                (
                    "foreground-owner.json",
                    b"synthetic-original-owner".as_slice(),
                ),
                ("foreground.lock", b"original-lock-token".as_slice()),
            ] {
                root.create_fixed(&writer, name, bytes, &|_| {}).unwrap();
            }
            if conflict {
                root.create_fixed(&writer, "advance.lock", b"foreign-existing-guard", &|_| {})
                    .unwrap();
            }
            let original_owner = root
                .read_raw(Path::new("foreground-owner.json"), 32768)
                .unwrap();
            let original_lock = root.read_raw(Path::new("foreground.lock"), 32768).unwrap();
            let owner = OwnedConfigurationRoot::open_existing(private, writer).unwrap();
            let tx: TransactionId = "fixture-previous-owner".try_into().unwrap();
            let maintenance = owner.begin_standalone_native(tx.clone(), false).unwrap();
            let task_name = format!(
                "StyxPilot-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..20]
            );
            let observation =
                WindowsLegacyObservation::capture_foreground_only(&task_name).unwrap();
            let boot = observation.checkpoint().unwrap();
            let evidence = WindowsPreviousBootEvidence {
                root: root.clone(),
                current_boot: boot,
                originals: vec![
                    root.read_raw(Path::new("deployment.json"), 32768).unwrap(),
                    original_owner,
                    original_lock,
                ],
            };
            let mut effect = WindowsBootRecoveryEffects::new(
                evidence,
                owner,
                maintenance,
                tx,
                b"synthetic-new-original-guard".to_vec(),
            )
            .unwrap();
            let result = effect.execute_archive(&observation);
            if conflict {
                assert!(result.is_err());
                // Original writable/delete pins intentionally exclude normal
                // read opens; inspect those same retained handles until drop.
                for pin in &effect.original_pins {
                    let original = &effect.evidence.originals[pin.index];
                    let handle = pin.handle.as_ref().unwrap();
                    assert_eq!(
                        &read_pin(handle, original.bytes()).unwrap(),
                        original.observation()
                    );
                    assert_eq!(
                        ffi::final_path(handle).unwrap(),
                        root.path.join(original.relative_path())
                    );
                }
                assert_eq!(
                    root.read_raw(Path::new("advance.lock"), 32768)
                        .unwrap()
                        .bytes(),
                    b"foreign-existing-guard"
                );
                assert!(effect.execute_archive(&observation).is_err());
            } else {
                result.unwrap();
                effect.observe_archived(&observation).unwrap();
                assert!(root.ensure_absent(Path::new("foreground.lock")).is_ok());
                assert!(effect.observe_complete(&observation).is_err());
                effect.finish_guards(&observation).unwrap();
                effect.observe_complete(&observation).unwrap();
                assert!(
                    root.ensure_absent(Path::new("foreground-recovery.lock"))
                        .is_ok()
                );
                for guard in GUARDS {
                    assert_eq!(
                        root.read_raw(Path::new(guard), 32768).unwrap().bytes(),
                        b"synthetic-new-original-guard"
                    );
                    assert!(ffi::open(&root.path.join(guard), false, true, false).is_err());
                }
                for pin in &effect.original_pins {
                    let old = &effect.evidence.originals[pin.index];
                    let actual = pin.post.as_ref().unwrap();
                    assert_eq!(old.observation().device, actual.device);
                    assert_eq!(old.observation().inode, actual.inode);
                }
                // Neither repeating an effect nor repeating a completion can
                // replay original renames. Read-only resync stays available.
                assert!(effect.execute_archive(&observation).is_err());
                assert!(effect.finish_guards(&observation).is_err());
                effect.observe_complete(&observation).unwrap();
            }
            drop(effect);
            drop(observation);
            drop(root);
            std::fs::remove_dir_all(base.join(&name)).unwrap();
            cleanup.0 = None;
        }
    }
}

#[path = "windows_previous_boot_binding.rs"]
mod binding;

pub(in crate::store) use binding::{
    WindowsLegacyMaintenancePlan, WindowsRecoveryOpenFailure, WindowsRestartCheckpoint,
};
